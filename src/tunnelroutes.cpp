#include "tunnelroutes.h"
#include "logger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QStringList>
#include <QVector>
#include <QWaitCondition>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern char** environ;

QString tunnelRoutesPath()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    return dir + QLatin1String("/tunnel-routes.txt");
}

QString tunnelRoutesTemplate()
{
    return QStringLiteral(
        "# One IPv4 network per line. A line starting with # is a comment.\n"
        "# Example. A more-specific connected route, such as your home LAN, stays local.\n"
        "10.0.0.0/8\n"
        "172.16.0.0/12\n"
        "192.168.0.0/16\n"
        "100.100.0.0/16\n");
}

bool tunnelRoutesTextOk(const QString& text, QString* error, int* count)
{
    int routes = 0;
    int lineNo = 0;
    const QRegularExpression cidr(QStringLiteral("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})$"));
    for (const QString& raw : text.split(QLatin1Char('\n'))) {
        ++lineNo;
        const QString line = raw.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }
        const QRegularExpressionMatch match = cidr.match(line);
        bool ok = match.hasMatch();
        for (int i = 1; ok && i <= 4; ++i) {
            ok = match.captured(i).toInt() <= 255;
        }
        if (ok) {
            ok = match.captured(5).toInt() <= 32;
        }
        if (!ok) {
            *error = QObject::tr("Line %1 is not an IPv4 network like 10.0.0.0/8").arg(lineNo);
            return false;
        }
        ++routes;
    }
    if (routes == 0) {
        *error = QObject::tr("The file has no routes.");
        return false;
    }
    *count = routes;
    return true;
}

namespace {

enum class RouteAction {
    Keep,
    Add,
    Replace
};

QString routeField(const QString& text, const QString& key)
{
    const QString prefix = key + QLatin1Char(':');
    for (const QString& raw : text.split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.startsWith(prefix)) {
            return line.mid(prefix.size()).trimmed();
        }
    }
    return QString();
}

QString dottedIPv4(const QString& text)
{
    const QStringList parts = text.split(QLatin1Char('.'));
    if (parts.isEmpty() || parts.size() > 4) {
        return QString();
    }
    quint32 ip = 0;
    for (int i = 0; i < 4; ++i) {
        int octet = 0;
        if (i < parts.size()) {
            bool ok = false;
            octet = parts.at(i).toInt(&ok);
            if (!ok || octet > 255) {
                return QString();
            }
        }
        ip = (ip << 8) | static_cast<quint32>(octet);
    }
    return QStringLiteral("%1.%2.%3.%4")
        .arg((ip >> 24) & 255)
        .arg((ip >> 16) & 255)
        .arg((ip >> 8) & 255)
        .arg(ip & 255);
}

bool prefixParts(const QString& cidr, QString* dest, QString* mask)
{
    const int slash = cidr.indexOf(QLatin1Char('/'));
    if (slash <= 0) {
        return false;
    }
    bool ok = false;
    const int bits = cidr.mid(slash + 1).toInt(&ok);
    const QString addr = dottedIPv4(cidr.left(slash));
    if (!ok || bits < 0 || bits > 32 || addr.isEmpty()) {
        return false;
    }
    const quint32 ip = ((addr.section(QLatin1Char('.'), 0, 0).toUInt() << 24)
        | (addr.section(QLatin1Char('.'), 1, 1).toUInt() << 16)
        | (addr.section(QLatin1Char('.'), 2, 2).toUInt() << 8)
        | addr.section(QLatin1Char('.'), 3, 3).toUInt());
    const quint32 bitsMask = bits == 0 ? 0 : (0xffffffffu << (32 - bits));
    *dest = dottedIPv4(QString::number((ip & bitsMask) >> 24) + QLatin1Char('.')
        + QString::number((ip & bitsMask) >> 16 & 255) + QLatin1Char('.')
        + QString::number((ip & bitsMask) >> 8 & 255) + QLatin1Char('.')
        + QString::number((ip & bitsMask) & 255));
    *mask = dottedIPv4(QString::number(bitsMask >> 24) + QLatin1Char('.')
        + QString::number((bitsMask >> 16) & 255) + QLatin1Char('.')
        + QString::number((bitsMask >> 8) & 255) + QLatin1Char('.')
        + QString::number(bitsMask & 255));
    return !dest->isEmpty() && !mask->isEmpty();
}

RouteAction decideRoute(const QString& routeGet, const QString& dest, const QString& mask, const QString& tun)
{
    if (dottedIPv4(routeField(routeGet, QLatin1String("destination"))) != dest
        || dottedIPv4(routeField(routeGet, QLatin1String("mask"))) != mask) {
        return RouteAction::Add;
    }
    if (routeField(routeGet, QLatin1String("interface")) == tun) {
        return RouteAction::Keep;
    }
    // shortcut: a conflicting route with no gateway is left alone, so a connected LAN route is not deleted
    if (routeField(routeGet, QLatin1String("gateway")).isEmpty()) {
        return RouteAction::Keep;
    }
    return RouteAction::Replace;
}

bool routesSelfCheck()
{
    QString error;
    int count = 0;
    if (!tunnelRoutesTextOk(tunnelRoutesTemplate(), &error, &count) || count != 4) {
        return false;
    }
    QString dest;
    QString mask;
    if (!prefixParts(QStringLiteral("10.0.0.0/8"), &dest, &mask)
        || dest != QLatin1String("10.0.0.0") || mask != QLatin1String("255.0.0.0")) {
        return false;
    }
    if (!prefixParts(QStringLiteral("172.16.0.0/12"), &dest, &mask)
        || dest != QLatin1String("172.16.0.0") || mask != QLatin1String("255.240.0.0")) {
        return false;
    }
    const QString viaDefault = QStringLiteral(
        "destination: default\n       mask: default\n  interface: utun4\n      flags: <UP,GATEWAY>\n");
    const QString onTun = QStringLiteral(
        "destination: 10.0.0.0\n       mask: 255.0.0.0\n  interface: utun4\n      flags: <UP,DONE,STATIC>\n");
    const QString viaGw = QStringLiteral(
        "destination: 10.0.0.0\n       mask: 255.0.0.0\n    gateway: 192.168.2.1\n  interface: en5\n      flags: <UP,GATEWAY,DONE,STATIC>\n");
    const QString lan = QStringLiteral(
        "destination: 192.168.2.0\n       mask: 255.255.255.0\n  interface: en5\n      flags: <UP,DONE,CLONING,STATIC>\n");
    return decideRoute(viaDefault, QStringLiteral("10.0.0.0"), QStringLiteral("255.0.0.0"), QStringLiteral("utun4")) == RouteAction::Add
        && decideRoute(onTun, QStringLiteral("10.0.0.0"), QStringLiteral("255.0.0.0"), QStringLiteral("utun4")) == RouteAction::Keep
        && decideRoute(viaGw, QStringLiteral("10.0.0.0"), QStringLiteral("255.0.0.0"), QStringLiteral("utun4")) == RouteAction::Replace
        && decideRoute(lan, QStringLiteral("192.168.2.0"), QStringLiteral("255.255.255.0"), QStringLiteral("utun4")) == RouteAction::Keep;
}

struct RouteResult {
    int code;
    QString text;
};

RouteResult runRoute(const QStringList& args)
{
    QVector<QByteArray> storage;
    storage.reserve(args.size() + 1);
    storage.append(QByteArray("/sbin/route"));
    for (const QString& arg : args) {
        storage.append(arg.toLocal8Bit());
    }
    QVector<char*> argv;
    argv.reserve(storage.size() + 1);
    for (QByteArray& item : storage) {
        argv.append(item.data());
    }
    argv.append(nullptr);

    int pipes[2] = { -1, -1 };
    if (pipe(pipes) != 0) {
        return { -1, QStringLiteral("pipe failed") };
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, pipes[0]);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipes[1]);

    pid_t pid = 0;
    const int spawned = posix_spawn(&pid, "/sbin/route", &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipes[1]);
    if (spawned != 0) {
        close(pipes[0]);
        return { -1, QStringLiteral("could not run route") };
    }

    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    QByteArray output;
    QElapsedTimer clock;
    clock.start();
    int status = 0;
    bool exited = false;
    // route waits 5s for a routing-socket reply. After the tun is down that reply never comes.
    const int budgetMs = 250;
    while (clock.elapsed() < budgetMs) {
        const int left = budgetMs - static_cast<int>(clock.elapsed());
        struct pollfd pfd = { pipes[0], POLLIN, 0 };
        poll(&pfd, 1, left > 0 ? left : 0);
        char buf[1024];
        ssize_t n = 0;
        while ((n = ::read(pipes[0], buf, sizeof buf)) > 0) {
            output.append(buf, static_cast<int>(n));
        }
        if (waitpid(pid, &status, WNOHANG) == pid) {
            exited = true;
            while ((n = ::read(pipes[0], buf, sizeof buf)) > 0) {
                output.append(buf, static_cast<int>(n));
            }
            break;
        }
    }
    close(pipes[0]);
    if (!exited) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return { -1, output.isEmpty() ? QStringLiteral("route timed out") : QString::fromLocal8Bit(output).trimmed() };
    }
    return { WIFEXITED(status) ? WEXITSTATUS(status) : -1, QString::fromLocal8Bit(output).trimmed() };
}

bool readRouteLines(QStringList* routes, QString* error)
{
    const QString path = tunnelRoutesPath();
    QString text = tunnelRoutesTemplate();
    if (QFileInfo::exists(path) && QFileInfo(path).size() > 0) {
        QFile in(path);
        if (!in.open(QIODevice::ReadOnly)) {
            *error = QObject::tr("Could not read %1").arg(path);
            return false;
        }
        text = QString::fromUtf8(in.readAll());
    }
    int count = 0;
    if (!tunnelRoutesTextOk(text, error, &count)) {
        return false;
    }
    routes->clear();
    for (const QString& raw : text.split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }
        routes->append(line);
    }
    return true;
}

QMutex g_mu;
QWaitCondition g_cv;
QString g_ifname;
QStringList g_applied;
QStringList g_failLog;
bool g_stop = false;
bool g_started = false;
std::thread g_thread;

void clearAppliedLocked()
{
    const QString ifname = g_ifname;
    for (const QString& cidr : g_applied) {
        if (!ifname.isEmpty()) {
            runRoute({ QStringLiteral("delete"), QStringLiteral("-net"), cidr, QStringLiteral("-interface"), ifname });
        }
    }
    g_applied.clear();
    g_failLog.clear();
}

void ensureLocked()
{
    static bool checked = false;
    if (!checked) {
        checked = true;
        if (!routesSelfCheck()) {
            Logger::instance().addMessage(QObject::tr("Tunnel route check failed"));
            return;
        }
    }
    if (g_ifname.isEmpty()) {
        return;
    }

    QString error;
    QStringList want;
    if (!readRouteLines(&want, &error)) {
        Logger::instance().addMessage(error);
        return;
    }

    for (const QString& cidr : g_applied) {
        if (!want.contains(cidr)) {
            runRoute({ QStringLiteral("delete"), QStringLiteral("-net"), cidr, QStringLiteral("-interface"), g_ifname });
        }
    }

    QStringList applied;
    for (const QString& cidr : want) {
        QString dest;
        QString mask;
        if (!prefixParts(cidr, &dest, &mask)) {
            continue;
        }
        const RouteResult current = runRoute({ QStringLiteral("-n"), QStringLiteral("get"), QStringLiteral("-net"), dest, QStringLiteral("-netmask"), mask });
        const RouteAction action = decideRoute(current.text, dest, mask, g_ifname);
        if (action == RouteAction::Keep) {
            applied.append(cidr);
            continue;
        }
        if (action == RouteAction::Replace) {
            runRoute({ QStringLiteral("delete"), QStringLiteral("-net"), cidr });
        }
        const RouteResult added = runRoute({ QStringLiteral("add"), QStringLiteral("-net"), cidr, QStringLiteral("-interface"), g_ifname });
        if (added.code != 0) {
            if (!g_failLog.contains(cidr)) {
                g_failLog.append(cidr);
                Logger::instance().addMessage(QObject::tr("Tunnel route %1 was not added: %2").arg(cidr, added.text));
            }
            continue;
        }
        g_failLog.removeAll(cidr);
        applied.append(cidr);
        Logger::instance().addMessage(QObject::tr("Tunnel route %1 via %2").arg(cidr, g_ifname));
    }
    g_applied = applied;
}

void keeperMain()
{
    g_mu.lock();
    while (!g_stop) {
        ensureLocked();
        g_cv.wait(&g_mu, 3000);
    }
    g_mu.unlock();
}

} // namespace

void tunnelRoutesSetIfname(const QString& ifname)
{
    QMutexLocker lock(&g_mu);
    g_ifname = ifname;
}

void tunnelRoutesEnsure()
{
#ifdef Q_OS_OSX
    QMutexLocker lock(&g_mu);
    ensureLocked();
#endif
}

void tunnelRoutesStartKeeper()
{
#ifdef Q_OS_OSX
    QMutexLocker lock(&g_mu);
    if (g_started) {
        return;
    }
    g_stop = false;
    g_started = true;
    g_thread = std::thread(keeperMain);
#endif
}

void tunnelRoutesStop()
{
#ifdef Q_OS_OSX
    {
        QMutexLocker lock(&g_mu);
        if (!g_started) {
            return;
        }
        g_stop = true;
        g_cv.wakeAll();
    }
    if (g_thread.joinable()) {
        g_thread.join();
    }
    QMutexLocker lock(&g_mu);
    clearAppliedLocked();
    g_ifname.clear();
    g_started = false;
    g_stop = false;
#endif
}

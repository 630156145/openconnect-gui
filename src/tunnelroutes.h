#pragma once

#include <QString>

QString tunnelRoutesPath();
QString tunnelRoutesTemplate();
bool tunnelRoutesTextOk(const QString& text, QString* error, int* count);

void tunnelRoutesSetIfname(const QString& ifname);
void tunnelRoutesEnsure();
void tunnelRoutesStartKeeper();
void tunnelRoutesStop();

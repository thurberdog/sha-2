#include "sha2.hpp"
#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    SHA2 * sha2 = new SHA2();
    return a.exec();
}

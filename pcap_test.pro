TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    my_pckt.cpp

HEADERS += \
    my_pckt.h

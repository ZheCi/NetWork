#ifndef __PACKSTRUCTGRAPH_H__
#define __PACKSTRUCTGRAPH_H__

#include <iomanip>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

extern int terminalRows; 
extern int terminalCols;

// 清空终端屏幕
void clearScreen();

//获取终端大小
void getTerminalSize(int& rows, int& cols);

// 设置光标位置
void setCursorPosition(int rows, int col);

// 打印图形
void echoPacketStructGraph(int rows);

#endif

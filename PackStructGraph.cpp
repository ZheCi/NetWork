#include "NetCard.h"
#include "PackStructGraph.h"

int terminalRows = 1;
int terminalCols = 1;

// 清空终端屏幕
void clearScreen() 
{
    cout << "\033[2J\033[1;1H";
}

// 获取终端大小
void getTerminalSize(int& rows, int& cols) {
    struct winsize size;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
    rows = size.ws_row;
    cols = size.ws_col;
}


// 设置光标位置
void setCursorPosition(int rows, int col) {
    std::cout << "\033[" << rows << ";" << col << "H";
}

// 应用层
void applicationLayerGraph(int rows, int cols)
{
    cout << COL(0, 41, 30);
    setCursorPosition(rows, cols);
    cout << setfill('-') << setw(11) << "-" << endl;
    setCursorPosition(rows+1, cols);
    cout << " 应用数据 |";
    setCursorPosition(rows+2, cols);
    cout << setfill('-') << setw(11) << "-" << endl;
    cout << OFFCOL;

}
// 传输层
void transportLayerGraph(int rows, int cols)
{
    cout << COL(0, 42, 30);
    setCursorPosition(rows, cols);
    cout << setfill('-') << setw(19) << "-" << endl;
    setCursorPosition(rows+1, cols);
    cout << " TCP/UDP/ICMP头部 |";
    setCursorPosition(rows+2, cols);
    cout << setfill('-') << setw(19) << "-" << endl;
    cout << OFFCOL;
}

// 网络层
void networkLayerGraph(int rows, int cols)
{
    cout << COL(0, 43, 30);
    setCursorPosition(rows, cols);
    cout << setfill('-') << setw(13) << "-" << endl;
    setCursorPosition(rows+1, cols);
    cout << " IP/RAP头部 |";
    setCursorPosition(rows+2, cols);
    cout << setfill('-') << setw(13) << "-" << endl;
    cout << OFFCOL;
}

// 数据链路层
void dataLinkLayerGraph(int rows, int cols)
{
    cout << COL(0, 44, 30);
    setCursorPosition(rows, cols);
    cout << setfill('-') << setw(18) << "-" << endl;
    setCursorPosition(rows+1, cols);
    cout << " Ethernet II头部 |";
    setCursorPosition(rows+2, cols);
    cout << setfill('-') << setw(18) << "-" << endl;
    cout << OFFCOL;
}


void echoPacketStructGraph(int rows)
{

    // 获取终端大小
    getTerminalSize(terminalRows, terminalCols);

    int appx = terminalCols - 10;
    int trax = appx - 19;
    int netx = trax - 13;
    int datx = netx - 18;

    setCursorPosition(rows+1, 1);
    cout << setfill('-') << setw(terminalCols - 11) << left << "应用层   ";
    applicationLayerGraph(rows, appx);

    setCursorPosition(rows+1+3, 1);
    cout << setfill('-') << setw(terminalCols - 11 - 19) << left << "传输层   ";
    applicationLayerGraph(rows + 3, appx);
    transportLayerGraph(rows + 3, trax);

    setCursorPosition(rows+1+3+3, 1);
    cout << setfill('-') << setw(terminalCols - 11 -19 -13) << left << "网络层   ";
    applicationLayerGraph(rows + 6, appx);
    transportLayerGraph(rows + 6, trax);
    networkLayerGraph(rows + 6, netx);

    setCursorPosition(rows+1+3+3+3, 1);
    cout << setfill('-') << setw(terminalCols -11 -19 -13 -16) << left << "数据链路层   ";
    applicationLayerGraph(rows + 9, appx);
    transportLayerGraph(rows + 9, trax);
    networkLayerGraph(rows + 9, netx);
    dataLinkLayerGraph(rows + 9 , datx);

    setCursorPosition(rows + 12, 1);
}

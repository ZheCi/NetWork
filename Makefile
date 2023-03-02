OBJE=main.o NetCard.o Sniffer.o Interface.o Option.o PackStructGraph.o SendTcp.o
CC=g++
CFLAGS+=-c -Wall

sniffer:$(OBJE)
	$(CC) $^ -o $@ -lpcap

%.o:%.cpp
	$(CC) $(CFLAGS) $^ -o $@

rm:
	rm -r *.o

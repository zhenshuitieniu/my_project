CC = g++ -fPIC -g -lpthread -std=c++11

#name all the object files
OBJS_1 = server.o string_lib.o common.o
OBJS_2 = client.o string_lib.o common.o

all : svr cli

svr : $(OBJS_1)
	$(CC) -o server $^

cli : $(OBJS_2)
	$(CC) -o client $^

%.o : %.c
	$(CC) -o $@ -c $^

clean :
	rm -rf $(OBJS_1) $(OBJS_2) server client




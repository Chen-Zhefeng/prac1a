prac1a.out:prac1a.o
	g++ -g -o prac1a.out prac1a.o -lssl -lcrypto 

prac1a.o:prac1a.cpp
	g++ -g -c prac1a.cpp

clean:
	rm -f *.o *.out

rebuild:clean prac1a.out

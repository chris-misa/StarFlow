all: starflowModel

starflowModel: starflowModel.cpp starFlow.h agg_levels.h
	g++ starflowModel.cpp -g -o starflowModel -lpcap -std=c++11

clean: 
	rm starflowModel

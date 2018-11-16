# Usage:
#   $ make              # Compile project
#   $ make debug        # Compile project with debug purpose
#   $ make clean        # Remove object files and deplist
#   $ make clean-all    # Remove object files, deplist and binaries

APP = dns-export

CXX = g++
RM = rm -f
CPPFLAGS = -g -std=c++11 -Wall -Wextra -Wpedantic
LDLIBS= -lpcap

SRCS = $(wildcard *.cpp)
OBJS = $(subst .cpp,.o,$(SRCS))

all: $(APP)

cd: clean clean-all

$(APP): $(OBJS)
	$(CXX) -o $(APP) $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend 2>/dev/null
	$(CXX) $(CPPFLAGS) -MM $^ >> ./.depend 2>/dev/null

clean:
	$(RM) $(OBJS) $(APP)

include .depend
# **************************************************************
# * Project:        DNS Export
# * File:		    Makefile
# * Author:		    Šimon Stupinský
# * University:     Brno University of Technology
# * Faculty: 	    Faculty of Information Technology
# * Course:	        Network Applications and Network Administration
# * Date:		    28.09.2018
# * Last change:    16.11.2018
# *
# * Subscribe:	Makefile
# *
# **************************************************************/

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

cd: all clean clean-all

$(APP): $(OBJS)
	$(CXX) -o $(APP) $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend 2>/dev/null
	$(CXX) $(CPPFLAGS) -MM $^ >> ./.depend 2>/dev/null

clean:
	$(RM) $(OBJS)

clean-all:
	$(RM) $(OBJS) $(APP)

include .depend
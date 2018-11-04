# Usage:
#   $ make              # Compile project
#   $ make debug        # Compile project with debug purpose
#   $ make clean        # Remove object files and deplist
#   $ make clean-all    # Remove object files, deplist and binaries

# Pack:
#   $ tar -cvf xstupi00.tar *

CPPC = g++
CPPFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS= -lpcap
DEPS = dep.list
SRC= $(wildcard *.cpp)
OBJ = $(SRC:.cpp=.o)
EXEC = dns-export

.PHONY: all clean clean-all

all: $(DEPS) $(EXEC)

%.o : %.cpp
	$(CPPC) $(CPPFLAGS) $(LDFLAGS) -c $<

$(DEPS): $(SRC)
	$(CPPC) -MM $(SRC) > $(DEPS)

-include $(DEPS)

$(EXEC): $(OBJ)
	$(CPPC) $(CPPFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(OBJ) $(DEPS)

clean-all:
	rm -f $(OBJ) $(DEPS) $(EXEC)
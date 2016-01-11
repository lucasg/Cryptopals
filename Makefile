 							
exercices := 01 02 03 04 05 06 07 08\
			 09 10 11 12 13 14 15 16\
			 17 18 19 20 21 22 23 24\
			 25 26 27 28 29 30 		\
			 33 34 35 36 37 38 39 40\
			 41 42 43 44 45 46 47 48
			      		              

_all: tools $(exercices)

ifeq (all, $(MAKECMDGOALS))
all : _all
endif  

SUBCOMMANDS := clean solve compile all #generate
INCLUDE = $(filter $(SUBCOMMANDS),$(MAKECMDGOALS))

ifeq (0, $(words $(INCLUDE)))
	COMMAND = all
else
	COMMAND = $(INCLUDE)
endif

.PHONY : exos
exos: $(exercices)

.PHONY : exercices
$(exercices):
ifeq ($(OS), Windows_NT)
	@$(MAKE) -C $(shell ./find_folder.sh "$@") $(COMMAND) 
else
	@$(MAKE) -C "$(shell ls -d \[$@\]*)" $(COMMAND) 
endif
	
.PHONY : tools
tools:
	$(MAKE) -C tools/ tools
	

#Do nothing
.PHONY : SUBCOMMANDS
$(SUBCOMMANDS):
	@:

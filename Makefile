# 							06
exercices := 01 02 03 04 05    07 08\
			 09 10 11 12 13 14 15 16\
			 17 18 19 20 21 22 23 24\
			 25 26 27 28 29 30

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
	@$(MAKE) -C "$(shell ls -d \[$@\]*)" $(COMMAND) 
	
	
.PHONY : tools
tools:
	$(MAKE) -C tools/ tools
	

#Do nothing
.PHONY : SUBCOMMANDS
$(SUBCOMMANDS):
	@:
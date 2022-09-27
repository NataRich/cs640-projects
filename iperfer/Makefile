ifeq ($(OS), Windows_NT)
	detected_OS := Windows
else
	detected_OS := $(shell uname)
endif

ifeq ($(detected_OS), Windows)
	CLEAN := del .\*.class
else
	CLEAN := rm -f ./*.class
endif

build:
	javac Iperfer.java Client.java Server.java

clean:
	$(CLEAN)
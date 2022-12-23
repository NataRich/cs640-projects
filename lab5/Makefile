JVC := javac
JVM := java
MAINDIR := edu/wisc/cs/sdn/simpledns
SRCDIR := src/$(MAINDIR)
OUTDIR := out/

ROOTIP := 192.5.5.241
EC2PATH := ec2.csv

build:
	$(JVC) -d $(OUTDIR) $(SRCDIR)/SimpleDNS.java $(SRCDIR)/packet/*.java

run:
	$(JVM) -classpath $(OUTDIR) $(MAINDIR)/SimpleDNS -r $(ROOTIP) -e $(EC2PATH)

clean:
	rm -r $(OUTDIR)
# If FPU instructions are generated by default, we have to use a special libm.a
MLDLIBS = $(LDLIBS) `case "$(CXXFLAGS)" in *-m68000* | *-mc68000* | *-msoft-float* ) echo -lm ;; * ) echo -lm881 ;; esac`
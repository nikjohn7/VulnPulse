# VulnPulse Makefile
# ====================
# Automation commands for data collection, deployment, and maintenance

.PHONY: help fetch upload deploy clean

# Default target - show help
.DEFAULT_GOAL := help

# Colors for terminal output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Display this help message
	@echo ""
	@echo "$(BLUE)VulnPulse - AI-Powered Vulnerability Intelligence$(RESET)"
	@echo "=================================================="
	@echo ""
	@echo "$(GREEN)Available commands:$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

fetch: ## Fetch vulnerability data from NVD, CISA KEV, and EPSS sources
	@echo "$(GREEN)Fetching vulnerability data...$(RESET)"
	python collector/fetch_all.py

upload: ## Upload local data files to Databricks Unity Catalog volume
	@echo "$(GREEN)Uploading data to Databricks...$(RESET)"
	@echo "Uploading NVD data..."
	databricks fs cp -r data/raw/nvd/ /Volumes/vulnpulse/bronze/raw_files/nvd/ --overwrite
	@echo "Uploading KEV data..."
	databricks fs cp -r data/raw/kev/ /Volumes/vulnpulse/bronze/raw_files/kev/ --overwrite
	@echo "Uploading EPSS data..."
	databricks fs cp -r data/raw/epss/ /Volumes/vulnpulse/bronze/raw_files/epss/ --overwrite
	@echo "$(GREEN)Upload complete!$(RESET)"

deploy: ## Validate and deploy Databricks asset bundle
	@echo "$(GREEN)Validating Databricks bundle...$(RESET)"
	databricks bundle validate
	@echo "$(GREEN)Deploying Databricks bundle...$(RESET)"
	databricks bundle deploy
	@echo "$(GREEN)Deployment complete!$(RESET)"

clean: ## Remove local data files
	@echo "$(YELLOW)Cleaning local data files...$(RESET)"
	rm -rf data/raw/nvd/*
	rm -rf data/raw/kev/*
	rm -rf data/raw/epss/*
	@echo "$(GREEN)Clean complete!$(RESET)"

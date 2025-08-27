#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSSecretScanner 配置管理模块
提供灵活的配置管理和自定义扫描规则
"""

import json
import os
from typing import Dict, List, Optional, Any
from pathlib import Path


class ScannerConfig:
    """扫描器配置管理类"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def _load_default_config(self) -> Dict:
        """加载默认配置"""
        return {
            "scan_settings": {
                "max_js_files": 30,
                "timeout": 15,
                "max_workers": 6,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            },
            "filter_settings": {
                "exclude_domains": [
                    "google-analytics.com",
                    "googletagmanager.com", 
                    "facebook.net",
                    "doubleclick.net",
                    "googlesyndication.com",
                    "scorecardresearch.com",
                    "amazon-adsystem.com",
                    "googletag.com",
                    "hotjar.com",
                    "intercom.io",
                    "zendesk.com",
                    "drift.com",
                    "crisp.chat"
                ],
                "exclude_js_patterns": [
                    r"analytics\.js",
                    r"gtag\.js", 
                    r"fbevents\.js",
                    r"mouseflow\.js",
                    r"fullstory\.js"
                ],
                "include_categories": [
                    "secrets",
                    "jwt_tokens",
                    "api_endpoints", 
                    "sensitive_paths",
                    "database_urls",
                    "cloud_config",
                    "webhooks",
                    "emails",
                    "phones",
                    "ip_addresses",
                    "urls_domains",
                    "id_cards",
                    "crypto_info"
                ],
                "exclude_test_data": True,
                "min_entropy": 3.5
            },
            "quality_settings": {
                "enable_entropy_check": True,
                "enable_similarity_filter": True,
                "enable_domain_relevance": True,
                "strict_mode": False,
                "quality_threshold": {
                    "critical": 0.9,
                    "high": 0.8,
                    "medium": 0.6,
                    "low": 0.4
                }
            },
            "output_settings": {
                "save_format": "json",  # json, csv, txt, all
                "create_html_report": True,
                "create_directory": True,
                "filename_prefix": "scan_",
                "include_source_urls": True,
                "compress_output": False
            },
            "performance_settings": {
                "max_file_size": 10 * 1024 * 1024,  # 10MB
                "connection_pool_size": 20,
                "retry_attempts": 3,
                "enable_caching": True,
                "cache_timeout": 3600
            },
            "security_settings": {
                "verify_ssl": False,
                "follow_redirects": True,
                "max_redirects": 5,
                "rate_limit": 0,  # 0 = 无限制
                "respect_robots_txt": False
            }
        }
    
    def load_config(self, config_file: str) -> bool:
        """从文件加载配置"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            
            # 递归合并配置
            self.config = self._merge_config(self.config, user_config)
            self.config_file = config_file
            return True
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            return False
    
    def save_config(self, config_file: str = None) -> bool:
        """保存配置到文件"""
        if config_file is None:
            config_file = self.config_file or "scanner_config.json"
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self.config_file = config_file
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def _merge_config(self, default: Dict, user: Dict) -> Dict:
        """递归合并配置"""
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """获取配置值（支持点分隔的路径）"""
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                value = value[key]
            
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> bool:
        """设置配置值（支持点分隔的路径）"""
        try:
            keys = key_path.split('.')
            config = self.config
            
            for key in keys[:-1]:
                if key not in config:
                    config[key] = {}
                config = config[key]
            
            config[keys[-1]] = value
            return True
        except Exception:
            return False
    
    def validate_config(self) -> List[str]:
        """验证配置的有效性"""
        errors = []
        
        # 检查必要的设置
        if self.get('scan_settings.max_js_files', 0) <= 0:
            errors.append("max_js_files 必须大于 0")
        
        if self.get('scan_settings.timeout', 0) <= 0:
            errors.append("timeout 必须大于 0")
        
        if self.get('scan_settings.max_workers', 0) <= 0:
            errors.append("max_workers 必须大于 0")
        
        # 检查质量阈值
        quality_threshold = self.get('quality_settings.quality_threshold', {})
        for level, threshold in quality_threshold.items():
            if not 0 <= threshold <= 1:
                errors.append(f"quality_threshold.{level} 必须在 0-1 之间")
        
        # 检查文件大小限制
        max_file_size = self.get('performance_settings.max_file_size', 0)
        if max_file_size <= 0:
            errors.append("max_file_size 必须大于 0")
        
        return errors
    
    def create_template_config(self, output_file: str = "config_template.json") -> bool:
        """创建配置模板文件"""
        template = {
            "scan_settings": {
                "max_js_files": 30,
                "timeout": 15,
                "max_workers": 6,
                "user_agent": "自定义User-Agent"
            },
            "filter_settings": {
                "exclude_domains": [
                    "example.com",
                    "test.com"
                ],
                "include_categories": [
                    "secrets",
                    "api_endpoints"
                ],
                "exclude_test_data": True
            },
            "output_settings": {
                "save_format": "all",
                "create_html_report": True,
                "filename_prefix": "my_scan_"
            },
            "_comments": {
                "scan_settings": "扫描基础设置",
                "filter_settings": "过滤和筛选设置", 
                "output_settings": "输出格式设置",
                "quality_settings": "质量控制设置",
                "performance_settings": "性能优化设置",
                "security_settings": "安全相关设置"
            }
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False


class CustomPatterns:
    """自定义正则模式管理"""
    
    def __init__(self, patterns_file: str = None):
        self.patterns_file = patterns_file
        self.custom_patterns = {}
        
        if patterns_file and os.path.exists(patterns_file):
            self.load_patterns(patterns_file)
    
    def load_patterns(self, patterns_file: str) -> bool:
        """从文件加载自定义模式"""
        try:
            with open(patterns_file, 'r', encoding='utf-8') as f:
                self.custom_patterns = json.load(f)
            
            self.patterns_file = patterns_file
            return True
        except Exception as e:
            print(f"加载模式文件失败: {e}")
            return False
    
    def save_patterns(self, patterns_file: str = None) -> bool:
        """保存模式到文件"""
        if patterns_file is None:
            patterns_file = self.patterns_file or "custom_patterns.json"
        
        try:
            with open(patterns_file, 'w', encoding='utf-8') as f:
                json.dump(self.custom_patterns, f, indent=2, ensure_ascii=False)
            
            self.patterns_file = patterns_file
            return True
        except Exception as e:
            print(f"保存模式文件失败: {e}")
            return False
    
    def add_pattern(self, category: str, pattern: str, min_length: int = 3, quality: str = 'medium', description: str = '') -> bool:
        """添加自定义模式"""
        try:
            if category not in self.custom_patterns:
                self.custom_patterns[category] = []
            
            pattern_info = {
                'pattern': pattern,
                'min_length': min_length,
                'quality': quality,
                'description': description
            }
            
            self.custom_patterns[category].append(pattern_info)
            return True
        except Exception:
            return False
    
    def remove_pattern(self, category: str, pattern: str) -> bool:
        """移除自定义模式"""
        try:
            if category in self.custom_patterns:
                self.custom_patterns[category] = [
                    p for p in self.custom_patterns[category] 
                    if p.get('pattern') != pattern
                ]
                
                if not self.custom_patterns[category]:
                    del self.custom_patterns[category]
                
                return True
        except Exception:
            pass
        
        return False
    
    def get_patterns(self, category: str = None) -> Dict:
        """获取模式"""
        if category:
            return self.custom_patterns.get(category, [])
        return self.custom_patterns
    
    def create_template_patterns(self, output_file: str = "patterns_template.json") -> bool:
        """创建模式模板文件"""
        template = {
            "custom_secrets": [
                {
                    "pattern": r"(?:my_api_key)\s*[:=]\s*[\"']([a-zA-Z0-9_\-+/=]{16,120})[\"']",
                    "min_length": 16,
                    "quality": "critical",
                    "description": "自定义API密钥模式"
                }
            ],
            "custom_endpoints": [
                {
                    "pattern": r"[\"']([/]myapi[/][a-zA-Z0-9_\-/.]{2,120})[\"']",
                    "min_length": 8,
                    "quality": "high", 
                    "description": "自定义API端点模式"
                }
            ],
            "_comments": {
                "pattern": "正则表达式模式",
                "min_length": "最小匹配长度",
                "quality": "质量等级: critical, high, medium, low",
                "description": "模式描述"
            }
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False


def create_config_files():
    """创建示例配置文件"""
    
    # 创建基础配置文件
    config = ScannerConfig()
    config.save_config("scanner_config.json")
    print("✅ 已创建基础配置文件: scanner_config.json")
    
    # 创建配置模板
    config.create_template_config("config_template.json")
    print("✅ 已创建配置模板文件: config_template.json")
    
    # 创建自定义模式管理
    patterns = CustomPatterns()
    patterns.create_template_patterns("patterns_template.json")
    print("✅ 已创建模式模板文件: patterns_template.json")
    
    # 创建高级配置示例
    advanced_config = {
        "scan_settings": {
            "max_js_files": 100,
            "timeout": 30,
            "max_workers": 12
        },
        "filter_settings": {
            "exclude_domains": [
                "cdn.jsdelivr.net",
                "unpkg.com", 
                "cdnjs.cloudflare.com"
            ],
            "min_entropy": 4.0,
            "exclude_test_data": True
        },
        "quality_settings": {
            "strict_mode": True,
            "enable_entropy_check": True,
            "quality_threshold": {
                "critical": 0.95,
                "high": 0.85,
                "medium": 0.70,
                "low": 0.50
            }
        },
        "output_settings": {
            "save_format": "all",
            "create_html_report": True,
            "compress_output": True
        }
    }
    
    with open("advanced_config.json", 'w', encoding='utf-8') as f:
        json.dump(advanced_config, f, indent=2, ensure_ascii=False)
    print("✅ 已创建高级配置文件: advanced_config.json")


if __name__ == '__main__':
    create_config_files()
    
    # 演示配置使用
    print("\n" + "=" * 50)
    print("配置使用演示")
    print("=" * 50)
    
    # 加载配置
    config = ScannerConfig("scanner_config.json")
    
    # 获取配置值
    max_js_files = config.get('scan_settings.max_js_files')
    print(f"📊 最大JS文件数: {max_js_files}")
    
    # 修改配置
    config.set('scan_settings.max_js_files', 50)
    print(f"🔧 修改后的最大JS文件数: {config.get('scan_settings.max_js_files')}")
    
    # 验证配置
    errors = config.validate_config()
    if errors:
        print(f"❌ 配置验证失败: {errors}")
    else:
        print("✅ 配置验证通过")
    
    # 演示自定义模式
    patterns = CustomPatterns()
    patterns.add_pattern(
        'custom_secrets',
        r'(?:my_secret_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-+/=]{20,120})["\']',
        min_length=20,
        quality='critical',
        description='我的自定义密钥模式'
    )
    
    patterns.save_patterns("my_patterns.json")
    print("✅ 已保存自定义模式: my_patterns.json")

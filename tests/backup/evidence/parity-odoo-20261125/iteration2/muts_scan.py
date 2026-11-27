T = ['tests.backup.test_ha_odoo.ScannerScriptTests']
MUTS = [
    ('S01', T, "        except Exception:\n            broken.append(name)\n", "        except ZeroDivisionError:\n            broken.append(name)\n"),
    ('S02', T, "config.parse_config([\"-c\", request[\"conf\"]] if os.path.isfile(request[\"conf\"]) else [])", "config.parse_config([])"),
    ('S03', T, "get_module_path(name, display_warning=False)", "get_module_path(name)"),
    ('S04', T, "            module.check_python_external_dependency(dep)\n            out[\"python\"][dep] = True\n        except Exception:\n            out[\"python\"][dep] = False\n",
     "            module.check_python_external_dependency(dep)\n            out[\"python\"][dep] = True\n        except Exception:\n            out[\"python\"][dep] = True\n"),
    ('S05', T, "except Exception as exc:\n    out[\"error\"] = type(exc).__name__\nsys.stdout.write(json.dumps(out))\n'''\n\n\ndef target_inventory",
     "except Exception as exc:\n    pass\nsys.stdout.write(json.dumps(out))\n'''\n\n\ndef target_inventory"),
    ('S06', T, "bool(manifest.get(\"installable\", True))", "True"),
]

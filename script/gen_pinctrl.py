#!/usr/bin/env python

"""
Copyright (c) 2024 Silicon Laboratories Inc.

SPDX-License-Identifier: Apache-2.0
"""

import argparse
import cmsis_svd
import lxml
import shutil
import tempfile
import urllib.request
import zipfile

from pathlib import Path

import cmsis_svd.parser

PIN_TOOL_URL = "https://github.com/SiliconLabs/gecko_sdk/releases/download/v4.4.3/pintool.zip"
CMSIS_PACK_PIDX_URL = "https://www.silabs.com/documents/public/cmsis-packs/SiliconLabs.pidx"
CMSIS_PACK_URL = "https://www.silabs.com/documents/public/cmsis-packs/SiliconLabs.GeckoPlatform_FAMILY_DFP.4.4.0.pack"

families = {
  "xg21": ["efr32mg21", "efr32bg21", "mgm21", "bgm21"],
  "xg22": ["efr32mg22", "efr32bg22", "efr32fg22", "mgm22", "bgm22", "efm32pg22"],
  "xg23": ["efr32fg23", "efr32sg23", "efr32zg23", "zgm23", "efm32pg23"], # "fgm23", 
  "xg24": ["efr32mg24", "efr32bg24", "mgm24", "bgm24"],
  "xg25": ["efr32fg25"],
  "xg26": ["efr32mg26", "efr32bg26"],
  "xg27": ["efr32mg27", "efr32bg27"],
  "xg28": ["efr32fg28", "efr32sg28", "efr32zg28", "efm32pg28"],
}

# Certain peripherals have different names in SVD and Pin Tool data;
# rename the SVD peripheral
peripheral_rename_map = {
  "FRC": "PTI",
  "LETIMER": "LETIMER0",
  "SYXO0": "HFXO0",
}
# Certain signals have different names in SVD and Pin Tool data;
# rename the SVD signal
signal_rename_map = {
  "CCC0": "CDTI0",
  "CCC1": "CDTI1",
  "CCC2": "CDTI2",
  "CCC3": "CDTI3",
}
# Certain signals have different names in SVD and Pin Tool data;
# rename the Pin Tool signal
pt_signal_rename_map = {
  "ACMPOUT": "DIGOUT",
  "COLOUT0": "COL_OUT_0",
  "COLOUT1": "COL_OUT_1",
  "COLOUT2": "COL_OUT_2",
  "COLOUT3": "COL_OUT_3",
  "COLOUT4": "COL_OUT_4",
  "COLOUT5": "COL_OUT_5",
  "COLOUT6": "COL_OUT_6",
  "COLOUT7": "COL_OUT_7",
  "ROWSENSE0": "ROW_SENSE_0",
  "ROWSENSE1": "ROW_SENSE_1",
  "ROWSENSE2": "ROW_SENSE_2",
  "ROWSENSE3": "ROW_SENSE_3",
  "ROWSENSE4": "ROW_SENSE_4",
  "ROWSENSE5": "ROW_SENSE_5",
  "ANTROLLOVER": "ANT_ROLL_OVER",
  "ANTRR0": "ANT_RR0",
  "ANTRR1": "ANT_RR1",
  "ANTRR2": "ANT_RR2",
  "ANTRR3": "ANT_RR3",
  "ANTRR4": "ANT_RR4",
  "ANTRR5": "ANT_RR5",
  "ANTSWEN": "ANT_SW_EN",
  "ANTSWUS": "ANT_SW_US",
  "ANTTRIG": "ANT_TRIG",
  "ANTTRIGSTOP": "ANT_TRIG_STOP",
  "BUFOUTREQINASYNC": "BUFOUT_REQ_IN_ASYNC",
  "USBVBUSSENSE": "USB_VBUS_SENSE",
}


def download_pintool(path: Path) -> None:
  dst = path / "pin_tool"
  if dst.exists():
    print("Skipping download of Pin Tool data, already exists")
    return
  print("Downloading Pin Tool data")
  with urllib.request.urlopen(PIN_TOOL_URL) as response:
    with tempfile.NamedTemporaryFile() as tmp_file:
      shutil.copyfileobj(response, tmp_file)

      with zipfile.ZipFile(tmp_file, 'r') as zip:
        zip.extractall(dst)


def download_pack(path: Path, family: str) -> None:
  dst = path / "pack" / family
  if dst.exists():
    print(f"Skipping download of CMSIS Pack for {family}, already exists")
    return
  print(f"Downloading CMSIS Pack for {family}")
  with urllib.request.urlopen(CMSIS_PACK_URL.replace("FAMILY", family.upper())) as response:
    with tempfile.NamedTemporaryFile() as tmp_file:
      shutil.copyfileobj(response, tmp_file)

      with zipfile.ZipFile(tmp_file, 'r') as zip:
        zip.extractall(dst)


def write_header(path: Path, family, peripherals: dict) -> None:
  lines = []
  lines.append("/*")
  lines.append(f" * Pin Control for Silicon Labs {family} devices")
  lines.append(" * Copyright (c) 2024 Silicon Laboratories Inc.")
  lines.append(" *")
  lines.append(" * SPDX-License-Identifier: Apache-2.0")
  lines.append(" */")
  lines.append("")
  lines.append("#include <dt-bindings/pinctrl/silabs-pinctrl-dbus.h>")

  for peripheral, signals in peripherals.items():
    lines.append("")
    for signal, data in signals.items():
      if signal == "_base":
        continue
      if "route" in data:
        lines.append(f"#define SILABS_DBUS_{peripheral}_{signal}(port, pin) SILABS_DBUS(port, pin, {signals['_base']}, {'1' if 'en' in data else '0'}, {data.get('en', 0)}, {data['route']})")
      else:
        print(f"WARN: No route register for {peripheral}_{signal}")

  for peripheral, signals in peripherals.items():
    lines.append("")
    for signal, data in signals.items():
      if signal == "_base":
        continue

      for port, pins in data['pinout'].items():
        for pin in sorted(pins):
          lines.append(f"#define {peripheral}_{signal}_P{chr(65 + port)}{pin} SILABS_DBUS_{peripheral}_{signal}({port}, {pin})")

  lines.append("")
  path.mkdir(parents=True, exist_ok=True)
  (path / f"{family}-pinctrl.h").write_text("\n".join(lines))


def parse_svd(peripherals, family: str) -> None:
  for svd_path in (args.workdir / "pack" / family / "SVD" / family.upper()).glob("*.svd"):
    print(f"Parsing SVD for {svd_path.stem}")
    parser = cmsis_svd.parser.SVDParser.for_xml_file(svd_path)
    gpio: cmsis_svd.parser.SVDPeripheral = next(filter(lambda p: p.name == "GPIO_NS", parser.get_device().peripherals))
    for reg in gpio.registers:
      if reg.name.endswith("_ROUTEEN"):
        peripheral = reg.name[:-8]
        if peripheral in peripheral_rename_map:
          peripheral = peripheral_rename_map[peripheral]
        if peripheral not in peripherals:
          peripherals[peripheral] = {"_base": reg.address_offset // 4}
        
        for field in reg.fields:
          if field.name.endswith("PEN"):
            signal = field.name[:-3]
            if signal in signal_rename_map:
              signal = signal_rename_map[signal]
            if signal not in peripherals[peripheral]:
              peripherals[peripheral][signal] = {}
            if "en" not in peripherals[peripheral][signal]:
              peripherals[peripheral][signal]["en"] = field.bit_offset

      if reg.name.endswith("ROUTE"):
        peripheral, signal = reg.name.split("_", 1)
        if peripheral in peripheral_rename_map:
          peripheral = peripheral_rename_map[peripheral]
        signal = signal[:-5]
        if signal in signal_rename_map:
          signal = signal_rename_map[signal]

        if peripheral not in peripherals:
          peripherals[peripheral]= {"_base": reg.address_offset // 4 }
        if signal not in peripherals[peripheral]:
          peripherals[peripheral][signal] = {}
        if "route" not in peripherals[peripheral][signal]:
          peripherals[peripheral][signal]["route"] = (reg.address_offset // 4) - peripherals[peripheral]["_base"]


def parse_pin_tool(peripherals, family: str):
  for pin_tool in (args.workdir / "pin_tool" / "platform" / "hwconf_data" / "pin_tool" / family).glob("*/PORTIO.portio"):
    print(f"Parsing Pin Tool for {pin_tool.parent.stem}")
    with open(pin_tool, 'r') as f:
      tree = lxml.etree.parse(f)

    for peripheral, signals in peripherals.items():
      for signal, data in signals.items():
        if signal == "_base":
          continue

        if signal in pt_signal_rename_map:
          pt_signal = pt_signal_rename_map[signal]
        else:
          pt_signal = signal

        if peripheral == "PRS0":
          pt_peripheral = f"PRS.{signal}"
          pt_signal_prefix = "PRS"
        else:
          pt_peripheral = peripheral
          pt_signal_prefix = peripheral

        if "pinout" not in data:
          data["pinout"] = {}
        pinout = {}
        for node in tree.getroot().xpath(f'portIo/pinRoutes/module[@name="{pt_peripheral}"]/selector[@name="{pt_signal_prefix}_{pt_signal}"]'):
          for loc in node.xpath(f'route[@name="{pt_signal}"]/location'):
            port = int(loc.attrib["portBankIndex"])
            pin = int(loc.attrib["pinIndex"])
            if port not in data["pinout"]:
              data["pinout"][port] = set()
            data["pinout"][port].add(pin)

          break
        else:
          print(f"WARN: No Pin Tool match for {peripheral}_{signal} for {pin_tool.parent.stem}")


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--workdir", "-w", default=Path(__file__).parent.absolute(), type=Path)
  parser.add_argument("--out", "-o", default=(Path(__file__).parent.absolute() / "out"), type=Path)
  parser.add_argument("--family", "-f", default="xg24")
  args = parser.parse_args()

  download_pintool(args.workdir)

  peripherals = {}

  for family in families[args.family]:
    download_pack(args.workdir, family)
    # Find DBUS register offsets for all peripheral signals from SVD
    parse_svd(peripherals, family)
    # Add available pins for all peripheral signals from Pin Tool data
    parse_pin_tool(peripherals, family)

  write_header(args.out, args.family, peripherals)

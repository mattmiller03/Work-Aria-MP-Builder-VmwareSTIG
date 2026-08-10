# vCommunity MP — offline build dependency

The [VCF Operations vCommunity Management Pack](https://github.com/vmbro/VCF-Operations-vCommunity)
is a **prerequisite** for the extended host coverage in this STIG pack: it
collects arbitrary ESXi advanced settings (and VM advanced parameters) as
properties **on the native `VMWARE/HostSystem` (and `VirtualMachine`) objects**,
so our compliance symptoms can bind to the advanced-setting checks the base
vCenter adapter does not expose. See `docs/native-attach-architecture.md`.

## Why this bundle exists

Building the vCommunity `.pak` on an **air-gapped** MP Builder fails: its
`Dockerfile` runs `pip3 install -r adapter_requirements.txt --upgrade`, which
tries to reach pypi.org from inside the container build. Two problems:

1. No pypi from the air-gapped Photon box.
2. `adapter_requirements.txt` pins `vmware-aria-operations-integration-sdk-lib~=1.0.0`,
   but `base-adapter:python-1.2.0` already ships the lib at 1.2.x — forcing 1.0.x
   would both require a download and risk downgrading the base harness.

`vcommunity-wheels.tgz` is a self-contained offline wheel set so the container
builds with no network. Contents (all from pypi, redistributable):

- `pyvmomi-8.0.3.0.1.tar.gz` (sdist — the one dep the base image lacks) + `six`
- `requests-2.25.1` + deps (`urllib3`, `certifi`, `idna`, `chardet`)
- `setuptools`, `wheel`, `packaging` (build backend for the pyvmomi sdist)

The SDK lib is intentionally **not** included — the build reuses the base image's
1.2.x, so the `~=1.0.0` pin is moot.

## How to use it

On the MP Builder (Photon) host, in the copied vCommunity project dir:

```bash
cd /opt/aria/Work-Aria-MP-Builder/VCF-Operations-vCommunity
mkdir -p wheels
tar xzf <this-repo>/deploy/vcommunity/vcommunity-wheels.tgz -C wheels/
```

**The SDK lib is required and is NOT in the base image.** `base-adapter:python-1.2.0`
does not ship `aria.ops`; the adapter imports it, so it must be installed into the
container. The `vcommunity-wheels.tgz` bundle here does NOT include it (it's the
one dep specific to your SDK version). Reuse the **Python 3.11 container wheels**
from the Azure pak project — they carry `vmware_aria_operations_integration_sdk_lib-1.1.0`
plus its `cffi`/`cryptography` C-ext deps, proven on this exact base:

```bash
cp /opt/aria/Work-Aria-MP-Builder/AzureGov/app/wheels/*.whl wheels/
# (do NOT use /opt/aria/wheels — those are Python 3.12 host wheels, wrong ABI)
ls wheels/ | grep -iE 'sdk_lib|cffi|cryptograph'   # must be present
```

Point the Dockerfile at the local wheels (offline) and install the SDK lib **by
name, unpinned** (takes 1.1.0; vCommunity's `~=1.0.0` pin is bypassed — the
`aria.ops` API it uses is stable and Azure runs 1.1.0 on this base):

```bash
cat > Dockerfile <<'EOF'
FROM base-adapter:python-1.2.0
COPY commands.cfg .
COPY wheels/ /tmp/wheels/
RUN pip3 install --no-cache-dir --no-index --find-links /tmp/wheels/ setuptools wheel && \
    pip3 install --no-cache-dir --no-index --no-build-isolation --find-links /tmp/wheels/ vmware-aria-operations-integration-sdk-lib pyvmomi requests
COPY app app
EOF
# NOTE: do NOT append `&& rm -rf /tmp/wheels` — the base image's final USER is the
# non-root aria-ops-adapter-user, which cannot delete the root-owned /tmp/wheels,
# so the rm fails and breaks the build. Leaving the wheels in the image is harmless.

# build the .pak the air-gapped / local-registry way (mirrors the Azure pak):
rm -rf build
sudo mp-build -i --no-ttl --registry-tag "214.73.76.134:5000/vcfops-vcommunity-adapter" -P 8181
# mp-build names the image from manifest "name" (iSDK_VCFOperationsvCommunity):
sudo docker tag isdk_vcfoperationsvcommunity-test:0.3.0 214.73.76.134:5000/vcfops-vcommunity-adapter:latest
sudo docker push 214.73.76.134:5000/vcfops-vcommunity-adapter:latest
```

Then upload the `.pak` in Aria (Add/Upgrade → ignore unsigned → EULA) and, on the
Cloud Proxy, `docker pull 214.73.76.134:5000/vcfops-vcommunity-adapter:latest`.

## Configure which settings it collects (STIG scope)

By default the adapter collects nothing. Point its working solution-config files at
the STIG-scoped lists generated in this directory so it collects exactly the
settings our compliance checks bind to:

- `stig-esxi-advanced-settings.xml` → the vCommunity `esxi_advanced_system_settings.xml`
  working config (32 ESXi advanced settings)
- `stig-vm-advanced-parameters.xml` → the vCommunity `vm_advanced_parameters.xml`
  working config (15 VM advanced parameters)
- `stig-advanced-settings-reference.md` — rule → setting → compliant value → property
  key map, used to author the compliance rules.

Collected property keys land on the native objects as
`vCommunity|Configuration|Advanced System Settings|<Setting>` (HostSystem) and
`vCommunity|Configuration|Advanced Parameters|<Setting>` (VirtualMachine).

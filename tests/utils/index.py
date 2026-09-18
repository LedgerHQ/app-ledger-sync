from utils.ApduDevice import createApduDevice
from utils.Device import createDevice, createDeviceFromKey


class device:
    software = createDevice
    software_from_key = createDeviceFromKey
    apdu = createApduDevice

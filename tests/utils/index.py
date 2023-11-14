from .Device import createDevice
from .ApduDevice import createApduDevice


class device:
    software = createDevice
    apdu = createApduDevice

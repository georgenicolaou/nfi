class MountPoints(object):
    '''
    This module is responsible for maintaining device mount locations specified
    by the user during the initialization of this case. These points should only
    be used during the initial case scanning and should be fed to the
    ApplicationParser, MiscParser and IDeviceVersion modules.
    
    For example, the Android /data partition mount point should be loaded using
    the MOUNT_DATA location and be requested using the same variable.
    
    #XXX At this time, only the IDeviceVersion makes use of this module
    '''
    
    MOUNT_DATA = "data"
    MOUNT_SYSTEM = "system"
    MOUNT_BACKUP_SIMPLE = "simple_backup"
    MOUNT_BACKUP_ADVANCED = "advanced_backup"
    
    
    def __init__(self):
        self.mounts = {}
        
    def set_mountpoint(self,name,location):
        self.mounts[name] = location
        
    def get_mountpoint(self,name):
        if name in self.mounts:
            return self.mounts[name]
        return None
class IDeviceVersion(object):
    '''
    This class should be overwritten by individual system modules. These
    modules should overwrite the 'populate_info' function in which they should
    attempt to read application and platform versions using any means necessary.
    These modules MUST eventually identify at least the platform version of the
    device.
    
    The application_versions dictionary should contain the application name as
    key and the application's version as value.
    '''
    DEFAULT_VERSION = -1
    
    name = "IDeviceVersion"
    device_version = -1
    application_versions = {}
    
    def __init__(self, print_queue, mounts, store=None ):
        self.print_queue = print_queue
        self.mounts = mounts
        self.store = store
        
    def populate_info(self):
        raise NotImplementedError
    
    def selfprint(self,msg):
        self.print_queue.put("[{}]: {}".format(self.name,msg))
    
    def has_version(self,version):
        if version in self.application_versions:
            return True
        return False
        
    def get_device_version(self):
        return self.device_version
    
    def get_application_version(self, app_name):
        if app_name in self.application_versions:
            return self.application_versions[app_name]
        return None
    
    def print_debug(self):
        appversions = '\n'.join(["\t\t{}: {}".format(n,v) for n,v in 
                                 self.application_versions.iteritems()])
        self.selfprint("""
        Platform Version: {}
        Application Versions:\n{}
        """.format( self.device_version, appversions ) )
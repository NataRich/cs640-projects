from mininet.util import *
def customConstructor( constructors, argStr ):
    """Return custom constructor based on argStr
    The args and key/val pairs in argsStr will be automatically applied
    when the generated constructor is later used.
    """
    cname, newargs, kwargs = splitArgs( argStr )
    constructor = constructors.get( cname, None )

    if not constructor:
        raise Exception( "error: %s is unknown - please specify one of %s" %
                         ( cname, constructors.keys() ) )

    def customized( name, *args, **params ):
        "Customized constructor, useful for Node, Link, and other classes"
        params = params.copy()
        params.update( kwargs )
        if not newargs:
            return constructor( name, *args, **params )
        if args:
            warn( 'warning: %s replacing %s with %s\n' % (
                  constructor, args, newargs ) )
        return constructor( name, *newargs, **params )

    customized.__name__ = 'customConstructor(%s)' % argStr
    return customized

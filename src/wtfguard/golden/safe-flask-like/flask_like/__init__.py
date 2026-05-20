__version__ = "3.1.0"


class App:
    def __init__(self, name):
        self.name = name
        self.routes = {}

    def route(self, path):
        def decorator(fn):
            self.routes[path] = fn
            return fn
        return decorator

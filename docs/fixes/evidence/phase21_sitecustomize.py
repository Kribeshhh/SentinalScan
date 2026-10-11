# Temporary audit hook: actual launcher/app configuration; replace only serving.
import flask,runpy,os

def verify(app,*args,**kwargs):
    runpy.run_path('/tmp/phase21_launcher_verify.py')['verify'](app)
flask.Flask.run=verify

def run(ctx):
    return dict(ctx['target'].dns, pinned_addresses=list(ctx['target'].addresses))

"""列表接口瘦身：campaigns（跨链攻击活动）只在详情接口提供，列表剥离防体积膨胀。"""
from server import slim_bundle


def test_slim_bundle_strips_campaigns():
    bundle = {'evidence': [1], 'alerts': [1], 'chains': [1], 'campaigns': [1],
              'victims': [1], 'graph': {}, 'metrics': {}}
    slim = slim_bundle(bundle)
    assert set(slim) == {'metrics'}


def test_slim_bundle_keeps_empty_bundle():
    assert slim_bundle(None) is None
    assert slim_bundle({}) == {}

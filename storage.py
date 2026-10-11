import os
from functools import lru_cache


def _settings():
    bucket = os.getenv("STORAGE_S3_BUCKET")
    region = os.getenv("AWS_REGION")
    if not bucket or not region:
        raise RuntimeError("Le stockage privé des photos n'est pas configuré.")
    return bucket, region


@lru_cache(maxsize=1)
def _client():
    import boto3

    _bucket, region = _settings()
    return boto3.client("s3", region_name=region)


def upload_private_object(data: bytes, key: str, content_type: str):
    bucket, _region = _settings()
    from io import BytesIO

    _client().upload_fileobj(
        BytesIO(data),
        bucket,
        key,
        ExtraArgs={"ContentType": content_type, "ServerSideEncryption": "AES256"},
    )


def upload_private_image(data: bytes, key: str, content_type: str):
    upload_private_object(data, key, content_type)


def create_private_object_url(key: str, expires_in: int = 300):
    bucket, _region = _settings()
    return _client().generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in,
    )


def create_private_image_url(key: str, expires_in: int = 300):
    return create_private_object_url(key, expires_in)


def delete_private_object(key: str):
    bucket, _region = _settings()
    _client().delete_object(Bucket=bucket, Key=key)


def delete_private_image(key: str):
    delete_private_object(key)

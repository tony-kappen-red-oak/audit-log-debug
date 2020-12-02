from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auditlog', '0007_object_pk_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='logentry',
            name='seen_by',
            field=models.ManyToManyField(
                to=settings.AUTH_USER_MODEL,
                blank=True,
                related_name="seen_by",
            ),
        ),
    ]

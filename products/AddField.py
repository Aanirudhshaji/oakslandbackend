from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ("products", "000X_previous_migration"),  # update with your last migration name
    ]

    operations = [
        migrations.AddField(
            model_name="category",
            name="slug",
            field=models.SlugField(max_length=220, unique=True, blank=True),
        ),
    ]

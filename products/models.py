from django.db import models
from django.utils.text import slugify
from django.conf import settings

User = settings.AUTH_USER_MODEL

class Category(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    description = models.TextField(blank=True)
    parent = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True, related_name="children")
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to="category_images/", null=True, blank=True)

    class Meta:
        verbose_name_plural = "Categories"
        ordering = ("name",)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug       :
            # simple slug creation (ensure uniqueness in more robust way if needed)
            base = slugify(self.name)
            slug = base
            i = 1
            while Category.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{i}"
                i += 1
            self.slug = slug
        super().save(*args, **kwargs)

    def get_children(self):
        return self.children.filter(is_active=True)

    def get_products(self):
        return Product.objects.filter(categories=self, is_active=True)


class Product(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=260, unique=True, blank=True)
    sku = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    categories = models.ManyToManyField(Category, related_name="products", blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    stock = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name)
            slug = base
            i = 1
            while Product.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{i}"
                i += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def primary_image(self):
        img = self.images.first()
        return img.image.url if img and img.image else None


class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="images")
    image = models.ImageField(upload_to="product_images/")
    alt_text = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"Image for {self.product.name}"

# products/models.py (add)
class ProductAttribute(models.Model):
    product = models.ForeignKey("Product", on_delete=models.CASCADE, related_name="attributes")
    key = models.CharField(max_length=100, db_index=True)      # e.g. "material", "color"
    value = models.CharField(max_length=200, db_index=True)    # e.g. "teak", "brown"

    class Meta:
        indexes = [
            models.Index(fields=["key", "value"]),
        ]

    def __str__(self):
        return f"{self.key}: {self.value}"

from rest_framework import viewsets, filters
from rest_framework.permissions import IsAdminUser, AllowAny
from .models import Category, Product, ProductImage
from .serializers import CategorySerializer, ProductSerializer, ProductImageSerializer
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.filter(is_active=True, parent__isnull=True)
    serializer_class = CategorySerializer
    lookup_field = "slug"
    permission_classes = [AllowAny]  # listing public; creation should be admin-only below

    def get_permissions(self):
        if self.action in ("create", "update", "partial_update", "destroy"):
            return [IsAdminUser()]
        return [AllowAny()]

    @action(detail=True, methods=["get"])
    def products(self, request, slug=None):
        category = self.get_object()
        products = Product.objects.filter(categories=category, is_active=True)
        page = self.paginate_queryset(products)
        serializer = ProductSerializer(page or products, many=True, context={"request": request})
        return self.get_paginated_response(serializer.data) if page is not None else Response(serializer.data)


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.filter(is_active=True)
    serializer_class = ProductSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "description", "sku"]
    ordering_fields = ["price", "created_at"]
    permission_classes = [AllowAny]

    def get_permissions(self):
        if self.action in ("create", "update", "partial_update", "destroy"):
            return [IsAdminUser()]
        return [AllowAny()]

    def get_queryset(self):
        qs = Product.objects.filter(is_active=True)
        category = self.request.query_params.get("category")
        if category:
            qs = qs.filter(categories__id=category)
        return qs.distinct()


class ProductImageViewSet(viewsets.ModelViewSet):
    queryset = ProductImage.objects.all()
    serializer_class = ProductImageSerializer
    permission_classes = [IsAdminUser]






# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
# from .models import Category, Product
# from .serializers import CategorySerializer, ProductSerializer


# # -------------------- LIST CATEGORIES --------------------
# class ListCategories(APIView):
#     permission_classes = [AllowAny]

#     def get(self, request):
#         categories = Category.objects.all()
#         serializer = CategorySerializer(categories, many=True)
#         return Response({"categories": serializer.data})


# # -------------------- LIST PRODUCTS --------------------
# class ListProducts(APIView):
#     permission_classes = [AllowAny]

#     def get(self, request):
#         products = Product.objects.all()
#         serializer = ProductSerializer(products, many=True)
#         return Response({"products": serializer.data})


# # -------------------- PRODUCT DETAIL --------------------
# class ProductDetail(APIView):
#     permission_classes = [AllowAny]

#     def get(self, request, product_id):
#         try:
#             product = Product.objects.get(id=product_id)
#             serializer = ProductSerializer(product)
#             return Response({"product": serializer.data})
#         except Product.DoesNotExist:
#             return Response({"error": "Product not found"}, status=404)


# # -------------------- ADD CATEGORY (Admin Only) --------------------
# class AddCategory(APIView):
#     permission_classes = [IsAuthenticated, IsAdminUser]

#     def post(self, request):
#         name = request.data.get("name")
#         description = request.data.get("description", "")
#         category = Category.objects.create(name=name, description=description)
#         return Response({"message": "Category added", "category": category.name})


# # -------------------- ADD PRODUCT (Admin Only) --------------------
# class AddProduct(APIView):
#     permission_classes = [IsAuthenticated, IsAdminUser]

#     def post(self, request):
#         category_name = request.data.get("category")
#         try:
#             category = Category.objects.get(name=category_name)
#         except Category.DoesNotExist:
#             return Response({"error": "Category not found"}, status=404)

#         product = Product.objects.create(
#             category=category,
#             name=request.data.get("name"),
#             description=request.data.get("description", ""),
#             price=request.data.get("price", 0),
#             stock=request.data.get("stock", 0),
#             image_url=request.data.get("image_url", "")
#         )
#         return Response({"message": "Product added", "product": product.name})




# import json
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import Category, Product
# from django.contrib.auth.decorators import user_passes_test, login_required

# # List all categories
# def list_categories(request):
#     categories = list(Category.objects.values())
#     return JsonResponse({"categories": categories})

# # List all products
# def list_products(request):
#     products = list(Product.objects.values())
#     return JsonResponse({"products": products})

# # Get product detail
# def product_detail(request, product_id):
#     try:
#         product = Product.objects.get(id=product_id)
#         data = {
#             "id": product.id,
#             "name": product.name,
#             "description": product.description,
#             "price": str(product.price),
#             "stock": product.stock,
#             "category": product.category.name,
#             "image_url": product.image_url
#         }
#         return JsonResponse({"product": data})
#     except Product.DoesNotExist:
#         return JsonResponse({"error": "Product not found"}, status=404)



# @csrf_exempt
# @login_required
# @user_passes_test(lambda u: u.is_staff)
# def add_category(request):
#     if request.method == "POST":
#         data = json.loads(request.body.decode("utf-8"))
#         name = data.get("name")
#         description = data.get("description", "")
#         category = category.objects.create(name=name, description=description)
#         return JsonResponse({"message": "Category added", "category": category.name})
#     return JsonResponse({"error": "Invalid request"}, status=400)



# @csrf_exempt
# @login_required
# @user_passes_test(lambda u: u.is_staff)
# def add_product(request):
#     if request.method == "POST":
#         data = json.loads(request.body.decode("utf-8"))
#         category_name = data.get("category")
#         try:
#             category = category.objects.get(name=category_name)
#         except category.DoesNotExist:
#             return JsonResponse({"error": "Category not found"}, status=404)

#         product = product.objects.create(
#             category=category,
#             name=data.get("name"),
#             description=data.get("description", ""),
#             price=data.get("price", 0),
#             stock=data.get("stock", 0),
#             image_url=data.get("image_url", "")
#         )
#         return JsonResponse({"message": "Product added", "product": product.name})
#     return JsonResponse({"error": "Invalid request"}, status=400)

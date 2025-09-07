from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CartItem, Order
from products.models import Product
from .serializers import CartItemSerializer, OrderSerializer
from rest_framework.decorators import api_view, permission_classes


# -------------------- ADD TO CART --------------------
@permission_classes([IsAuthenticated])
class AddToCart(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        try:
            product = Product.objects.get(id = product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)
        
        if product.stock < quantity:
            return Response({"error": "Not enough stock available"}, status=400)
        
        cart_item, created = CartItem.objects.get_or_create(
            user=request.user, product=product
        )
        if not created:
            # New total if updating existing cart item
            new_quantity = cart_item.quantity + quantity
            if product.stock < new_quantity:
                return Response({"error": "Not enough stock available"}, status=400)
            cart_item.quantity = new_quantity
        else:
            cart_item.quantity = quantity

        cart_item.save()
        return Response({"message": "Product added to cart", "product": product.name})


# -------------------- VIEW CART --------------------
class ViewCart(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cart_items = CartItem.objects.filter(user=request.user)
        serializer = CartItemSerializer(cart_items, many=True)
        total = sum([item.total_price() for item in cart_items])
        return Response({"cart": serializer.data, "total_amount": float(total)})


# -------------------- CHECKOUT --------------------
class Checkout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        cart_items = CartItem.objects.filter(user=request.user)
        if not cart_items.exists():
            return Response({"error": "Cart is empty"}, status=400)

        # Verify stock before placing order
        for item in cart_items:
            if item.quantity > item.product.stock:
                return Response(
                    {"error": f"Not enough stock for {item.product.name}"},
                    status=400
                )

        total = sum([item.total_price() for item in cart_items])
        order = Order.objects.create(user=request.user, total_amount=total)
        order.items.set(cart_items)
        order.save()

        # Reduce stock
        for item in cart_items:
            item.product.stock -= item.quantity
            item.product.save()

        # Clear cart
        cart_items.delete()

        serializer = OrderSerializer(order)
        return Response({"message": "Order placed successfully", "order": serializer.data})



# -------------------- ORDER HISTORY --------------------
class OrderHistory(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        orders = Order.objects.filter(user=request.user).order_by("-created_at")
        serializer = OrderSerializer(orders, many=True)
        return Response({"orders": serializer.data})




# import json
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from django.contrib.auth.decorators import login_required
# from .models import CartItem, Order
# from products.models import Product
# from django.contrib.auth import get_user_model

# User = get_user_model()

# @login_required
# @csrf_exempt
# def add_to_cart(request):
#     if request.method == "POST":
#         data = json.loads(request.body.decode("utf-8"))
#         product_id = data.get("product_id")
#         quantity = data.get("quantity", 1)

#         try:
#             product = Product.objects.get(id=product_id)
#         except Product.DoesNotExist:
#             return JsonResponse({"error": "Product not found"}, status=404)

#         cart_item, created = CartItem.objects.get_or_create(
#             user=request.user, product=product
#         )
#         if not created:
#             cart_item.quantity += quantity
#         else:
#             cart_item.quantity = quantity
#         cart_item.save()

#         return JsonResponse({"message": "Product added to cart", "product": product.name})
#     return JsonResponse({"error": "Invalid request"}, status=400)


# @login_required
# def view_cart(request):
#     cart_items = CartItem.objects.filter(user=request.user)
#     items = []
#     total = 0
#     for item in cart_items:
#         items.append({
#             "product": item.product.name,
#             "quantity": item.quantity,
#             "price": float(item.product.price),
#             "total_price": float(item.total_price())
#         })
#         total += item.total_price()
#     return JsonResponse({"cart": items, "total_amount": float(total)})


# @login_required
# @csrf_exempt
# def checkout(request):
#     cart_items = CartItem.objects.filter(user=request.user)
#     if not cart_items.exists():
#         return JsonResponse({"error": "Cart is empty"}, status=400)

#     total = sum([item.total_price() for item in cart_items])
#     order = Order.objects.create(user=request.user, total_amount=total)
#     order.items.set(cart_items)
#     order.save()

#     # Clear cart
#     cart_items.delete()

#     return JsonResponse({"message": "Order placed successfully", "order_id": order.id})


# @login_required
# def order_history(request):
#     orders = Order.objects.filter(user=request.user).order_by("-created_at")
#     data = []
#     for order in orders:
#         items = [{"product": item.product.name, "quantity": item.quantity} for item in order.items.all()]
#         data.append({
#             "order_id": order.id,
#             "items": items,
#             "total_amount": float(order.total_amount),
#             "status": order.status,
#             "created_at": order.created_at
#         })
#     return JsonResponse({"orders": data})

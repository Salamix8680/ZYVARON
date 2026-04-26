#def print_circum(radius):
   # pi=3.14159
   # circumference= 2 * pi * radius
   # print('radius', radius, 'circumference', circumference)

#Function calls with different values

#print_circum(7)

#print_circum(8)

#print_circum(9)


# PART 2


def online_store():

    #prices of items

    Item1 = 200
    Item2 = 400
    Item3 = 600

    print("Online Store")
    
    print("=======================")
    
    print("Product(S)\t\tPrice")

    # Individual Items
    
    print("Item 1\t\t\t", Item1)
    print("Item 2\t\t\t", Item2)
    print("Item 2\t\t\t", Item3)

    # Combo Package 10% discount

    Combo1 = (Item1 + Item2) * 0.9
    Combo2 = (Item2 + Item3) * 0.9
    Combo3 = (Item1 + Item3) * 0.9

    # Gift Package 25%

    Combo4 = (Item1 + Item2 + Item3) * 0.75

    print("(item 1 + item 2)\t", Combo1)
    print("(item 2 + item 3)\t", Combo2)
    print("(item 1 + item 3)\t", Combo3)
    print("(item 1 + 2 + 3)\t", Combo4)

    print("===============================")
    print("For delivery", "Call:09024790860")
    

# Calling the function
online_store()

print ((1+1)**(5-2))

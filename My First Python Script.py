# My First Python Script

name = input("What is our name?")
age = int(input("How old are you?"))


current_year = int(input("What is your current year?"))
year_turn_100 = current_year + (100 - age)

print(f"Hi {name}, you will turn 100 years old in the year {year_turn_100}.")

FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get install -y build-essential valgrind

# Copy the source code
COPY . /app

# Set the working directory
WORKDIR /app

# Compile the source code
RUN gcc -o main example_main.c lib/heap.h lib/heap.c

# Run valgrind
CMD ["valgrind", "--leak-check=full", "--show-leak-kinds=all", "--track-origins=yes", "./main"]
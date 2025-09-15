#!/bin/bash

# Test script for WildFly 36 Arquillian setup
# This script demonstrates how to run tests with the new WildFly 36 profiles

echo "=== JBoss Seam WildFly 36 Arquillian Test Script ==="
echo

# Check if we're in the right directory
if [ ! -f "pom.xml" ]; then
    echo "Error: Please run this script from the root of the jboss-seam project"
    exit 1
fi

echo "1. Testing booking example with WildFly 36 managed container..."
echo "Command: cd examples/booking/booking-tests && mvn clean test -Darquillian=wildfly-managed-36 -Dtest=WildFly36BookingTest"
echo

echo "2. Testing booking example with WildFly 36 remote container..."
echo "Command: cd examples/booking/booking-tests && mvn clean test -Darquillian=wildfly-remote-36 -Dtest=WildFly36BookingTest"
echo

echo "3. Testing seam integration tests with WildFly 36..."
echo "Command: cd seam-integration-tests && mvn clean test -Darquillian=wildfly-managed-36"
echo

echo "4. Available Arquillian profiles:"
echo "   - jbossas-managed-7     (existing JBoss AS 7.1.1)"
echo "   - jbossas-remote-7      (existing JBoss AS 7.1.1)"
echo "   - wildfly-managed-36    (new WildFly 36 managed)"
echo "   - wildfly-remote-36     (new WildFly 36 remote)"
echo

echo "5. To run a specific test:"
echo "   mvn clean test -Darquillian=wildfly-managed-36 -Dtest=YourTestClass"
echo

echo "6. To run all tests in a module:"
echo "   mvn clean test -Darquillian=wildfly-managed-36"
echo

echo "Note: The managed profile will automatically download WildFly 36 on first run."
echo "      This may take several minutes depending on your internet connection."
echo

# Uncomment the following lines to actually run a test
# echo "Running a quick test..."
# cd examples/booking/booking-tests
# mvn clean compile test-compile -Darquillian=wildfly-managed-36

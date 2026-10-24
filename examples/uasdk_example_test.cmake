# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

# Registers an example's behaviour test: run the binary, compare its whole normalised stdout to the
# example's expected_output.txt. See tooling/examples/run_example_test.py.
#
# Skipped when the example is built standalone against an installed SDK, where the harness and the
# Python interpreter are not necessarily present.
function(uasdk_add_example_test target)
    cmake_parse_arguments(ARG "FIXED_PORTS" "TIMEOUT;INTERRUPT_WHEN;SERVER;RESTART_SERVER_WHEN" "ARGS;SERVER_ARGS;MASK" ${ARGN})
    if (NOT UASDK_EXAMPLE_TEST_RUNNER)
        return()
    endif ()
    if (NOT ARG_TIMEOUT)
        set(ARG_TIMEOUT 60)
    endif ()
    set(_runner_args)
    if (ARG_SERVER)
        list(APPEND _runner_args --server "$<TARGET_FILE:${ARG_SERVER}>")
        foreach (_server_argument IN LISTS ARG_SERVER_ARGS)
            list(APPEND _runner_args "--server-arg=${_server_argument}")
        endforeach ()
    endif ()
    # By default the runner asks every listener for port 0 and hands the client whatever the
    # operating system chose, so no test reserves a port number. FIXED_PORTS opts out, for a URL
    # that is an identity rather than a socket - see the runner's --fixed-ports.
    if (ARG_FIXED_PORTS)
        list(APPEND _runner_args --fixed-ports)
    endif ()
    if (ARG_RESTART_SERVER_WHEN)
        list(APPEND _runner_args --restart-server-when "${ARG_RESTART_SERVER_WHEN}")
    endif ()
    if (ARG_INTERRUPT_WHEN)
        list(APPEND _runner_args --interrupt-when "${ARG_INTERRUPT_WHEN}")
    endif ()
    # A value that legitimately differs between two correct runs and is not already normalised - a
    # DER length, say. Keep these rare: a mask over the number an example exists to show removes the
    # only thing its golden was checking.
    foreach (_mask IN LISTS ARG_MASK)
        list(APPEND _runner_args "--mask=${_mask}")
    endforeach ()
    foreach (_argument IN LISTS ARG_ARGS)
        # `--arg=value`, not `--arg value`: argparse refuses to take a dash-leading token as an
        # option's value, and these arguments are themselves options such as --endpoint.
        list(APPEND _runner_args "--arg=${_argument}")
    endforeach ()
    add_test(NAME "example.${target}"
        COMMAND "${Python3_EXECUTABLE}" "${UASDK_EXAMPLE_TEST_RUNNER}"
            --binary "$<TARGET_FILE:${target}>"
            --expected "${CMAKE_CURRENT_SOURCE_DIR}/expected_output.txt"
            --timeout "${ARG_TIMEOUT}"
            ${_runner_args})
    math(EXPR _ctest_timeout "${ARG_TIMEOUT} + 30")
    # The runner gives every test its own operating-system-assigned port, so these run in parallel
    # and nothing has to be allocated. The examples keep a realistic fixed default in their source,
    # which is what a reader copies; it is never the port a test binds.
    set_tests_properties("example.${target}" PROPERTIES TIMEOUT ${_ctest_timeout})
    # ...except a FIXED_PORTS test, which opts out of the assigned port and reserves a real one. The
    # sentence above is then no longer true of it, and both FIXED_PORTS tests reserve
    # 127.0.0.1:4864: the client listens on it, the server dials it. ctest runs -j 4, so without a
    # lock the two overlap, the server of one test dials the client of the other, and the client
    # refuses a certificate it never expected to see - BadSecurityChecksFailed, on a pair that is
    # correct in isolation. The lock is shared rather than per-port because reserving a real port is
    # itself the thing being serialised, and there are two such tests.
    if (ARG_FIXED_PORTS)
        set_tests_properties("example.${target}" PROPERTIES RESOURCE_LOCK uasdk-example-fixed-ports)
    endif ()
endfunction()

# Session Context

## User Prompts

### Prompt 1

Running tests for the changes on this branch failed on cicd with the following stacktrace (just a snipped, the actual file is gigantic):

2026-03-10T02:06:15.6575613Z Gradle Test Executor 1 finished executing tests.
2026-03-10T02:06:16.9631082Z 
2026-03-10T02:06:16.9636608Z 
2026-03-10T02:06:16.9637188Z > Task :test FAILED
2026-03-10T02:06:16.9638884Z 02:06:15.389 [SpringContextShutdownHook] DEBUG org.springframework.context.support.GenericApplicationContext - Closing org.springframework.cont...

### Prompt 2

2026-03-10T02:05:48.4843195Z     02:05:48.401 [Test worker] INFO org.springframework.test.context.transaction.TransactionContext - Rolled back transaction for test: [DefaultTestContext@42a75f59 testClass = FrameCompleteHandlerTests, testInstance = com.imageworks.spcue.test.dispatcher.FrameCompleteHandlerTests@6606a6a8, testMethod = testDependRetryExhausted@FrameCompleteHandlerTests, testException = java.lang.AssertionError: expected:<1> but was:<0>, mergedContextConfiguration = [MergedContext...

### Prompt 3

[Request interrupted by user for tool use]

### Prompt 4

Tests are printing the entire stack trace and even queries, reduce the verbosity of tests running on the cicd pipeline "Build Cuebot and run unit tests"


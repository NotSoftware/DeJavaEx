/*
MIT License

Copyright (c) 2026 DeJavaEx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package fixtures;

public final class BehaviorFixture {
    private static final String TOOL_MARKER = "Allatori protector";
    private static int state;

    public void referenceSensitiveApis() throws Exception {
        Runtime.getRuntime().exec("not-executed-by-analysis");
        new ProcessBuilder("cmd.exe").start();
        Class.forName("fixtures.HiddenPayload");
        new java.net.Socket("example.invalid", 80);
        javax.crypto.Cipher.getInstance("AES");
    }

    public int readFieldState() {
        return state;
    }

    public Runnable buildDynamicCallSite() {
        return () -> state++;
    }
}
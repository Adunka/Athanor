#[test]
fn adds_two_pushed_words() {
    let mut compiler = athanor_jit::Compiler::new().unwrap();
    // PUSH1 2, PUSH1 3, ADD, STOP
    let code = [0x60, 0x02, 0x60, 0x03, 0x01, 0x00];
    let compiled = compiler.compile(&code).unwrap();
    let mut machine = athanor_jit::Machine::new(1_000);
    let exit = unsafe { machine.run(compiled.entry()) };
    assert_eq!(exit, athanor_jit::Exit::Stop);
    assert_eq!(machine.stack(), vec![athanor::U256::from(5u64)]);
    // 3 + 3 for the pushes, 3 for the ADD, STOP is free.
    assert_eq!(machine.gas(), 1_000 - 9);
}

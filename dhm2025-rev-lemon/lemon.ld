SECTIONS
{
    .lemonade.descriptors : {
        PROVIDE(__lemonade_start = .);
        *(.lemonade.descriptors)
        PROVIDE(__lemonade_end = .);
    }
}
INSERT AFTER .rodata;

#include <stdio.h>
#include <assert.h>

#include <r_core.h>

bool print_flag_name_cb(RFlagItem *fi, void *user) {
    printf("%s\n", fi->name);
    return true;
}

int main() {
    RCore *core = r_core_new();

    r_core_task_sync_begin(&core->tasks);

    if (r_config_get_i(core->config, "cfg.plugins")) {
        r_core_loadlibs(core, R_CORE_LOADLIBS_ALL, NULL);
    }

    // load binary
    RCoreFile *cfile = r_core_file_open(core, "pppd", R_PERM_RW, UT64_MAX);
    assert(cfile);
    bool err = r_core_bin_load(core, "pppd", UT64_MAX);
    assert(err);

    // print something initial
    printf("entry : %llx\n", core->offset);
    //r_flag_foreach(core->flags, print_flag_name_cb, NULL);

    // Init entry point vaddr (from libr/main/radare2.c)
    RBinObject *o = r_bin_cur_object(core->bin);
    if (o && !o->regstate) {
        RFlagItem *fi = r_flag_get(core->flags, "entry0");
        //printf("%llx\n", fi->offset);
        if (fi) {
            r_core_seek(core, fi->offset, true);
        } else {
            if (o) {
                RList *sections = r_bin_get_sections(core->bin);
                RListIter *iter;
                RBinSection *s;
                r_list_foreach(sections, iter, s) {
                    if (s->perm & R_PERM_X) {
                        ut64 addr = s->vaddr ? s->vaddr : s->paddr;
                        r_core_seek(core, addr, true);
                        break;
                    }
                }
            }
        }
    }

    r_core_seek(core, core->offset, true); // read current block


    // more printing before anal
    printf("bininfo rclass : %s\n", core->bin->cur->o->info->rclass);
    printf("bininfo bclass : %s\n", core->bin->cur->o->info->bclass);
    printf("bininfo arch : %s\n", o->info->arch);
    printf("before anal : functions %x\n", core->anal->fcns->length);

    r_core_anal_all(core);

    printf("after anal : functions %x\n", core->anal->fcns->length);

    RListIter *iter;

    RAnalFunction *func;
    r_list_foreach(core->anal->fcns, iter, func) {
        printf("Function %llx > %s : %d bbs, %d instrs\n", func->addr, func->name, func->bbs->length, func->ninstr);
    }

    printf("dump entry bb:\n");
    RAnalFunction *entryf = r_anal_get_fcn_in(core->anal, core->offset, 0);
    RAnalBlock *bb;
    r_list_foreach(entryf->bbs, iter, bb) {
        printf(" > %llx\n", bb->addr);
        r_core_seek(core, bb->addr, true);

        // get asm 1
        RAsmOp op;
        int nop = r_asm_disassemble(core->rasm, &op, core->block, bb->size);
        printf("  %d - %s\n", nop, r_asm_op_get_asm(&op));

        // get asm 2
        RAsmCode *c = r_asm_mdisassemble(core->rasm, core->block, bb->size);
        printf("%s\n", c->assembly);
    }


    r_core_task_sync_end(&core->tasks);

    r_core_file_close(core, cfile);
    r_core_free(core);
    return 0;
}

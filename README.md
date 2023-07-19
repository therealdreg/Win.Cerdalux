<div align="center">
  <img width="125px" src="assets/logo.png" />
  <h1>Win.Cerdalux</h1>
  <br/>
  <p><i>WinXPSP2.Cermalus on stereoids, supporting all 32 bits Windows version. Windows Kernel Virus</i></p>
</div>

Based from WinXPSP2.Cermalus by Pluf/7A69ML: [therealdreg/WinXPSP2.Cermalus](https://github.com/therealdreg/WinXPSP2.Cermalus/)

# dev steps

- Clone this repo in C:\
- Download & install in C:\ **Masm32v11r** [/stuff/masm32v11r.zip](/stuff/masm32v11r.zip)  
- Download & install in C:\ **RadASM-2.2.2.4-FullPackage.zip** [/stuff/RadASM-2.2.2.4-FullPackage.zip](/stuff/RadASM-2.2.2.4-FullPackage.zip)  
- Add **C:\masm32\bin** to **%PATH%**
- Open **/source/cerdalux.rap** in Radasm2 IDE and Build All
- Done!

## debug build

![radasmdebugbuild](assets/radasmdebugbuild.png)

# To-Do

## General

- [ ] dropper with .ico (new logo)
- [ ] CI/CD implementation for testing
- [ ] Write documentation
- [x] port to Masm32v11r
- [x] create Radasm project  

## Features

- [ ] Multi-core support: KeSetTargetProcessorDpc + KeInsertQueueDpc...
- [ ] Support newer Windows versions
    - [x] Windows XP SP2 
- [ ] 64-bit support

# Credits

- Pluf/7A69ML original author WinXPSP2.Cermalus
- David Reguera Garcia aka Dreg

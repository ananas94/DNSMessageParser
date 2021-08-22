//https://www.cppstories.com/2018/02/factory-selfregister/

#include <memory>
#include <map>
#include <iostream>

class ICompressionMethod
{
public:
	ICompressionMethod() = default;
	virtual ~ICompressionMethod() = default;
	virtual std::string SAYMYNAME() =0;
};


class CompressionMethodFactory
{
public:
    using TCreateMethod = std::unique_ptr<ICompressionMethod>(*)();
	TCreateMethod m_CreateFunc;
    
public:
	CompressionMethodFactory() = delete;

	static bool Register(const std::string name, TCreateMethod createFunc)
	{
	    if (auto it = GetMap().find(name); it == GetMap().end())
	    {
		    GetMap()[name] = createFunc;
//		    std::cout << name << " registered\n";
		    return true;
	    }
        return false;
    }
	
	static std::unique_ptr<ICompressionMethod> Create(const std::string& name)
	{
	    if (auto it = GetMap().find(name); it != GetMap().end())
		    return it->second();

	    return nullptr;
	}

	static std::map<std::string, TCreateMethod>& GetMap(){
		static std::map<std::string, TCreateMethod> s_methods;
		return s_methods;
	}

};


//std::map<std::string, CompressionMethodFactory::TCreateMethod> CompressionMethodFactory::s_methods;

template <typename T>
class RegisteredInFactory
{
	virtual void Compress() { s_bRegistered; }
protected:
    static bool s_bRegistered;
};

template <typename T>
bool RegisteredInFactory<T>::s_bRegistered = CompressionMethodFactory::Register(T::GetFactoryName(), T::CreateMethod);

class ZipCompression : public ICompressionMethod, public RegisteredInFactory<ZipCompression>
{
public:
	//virtual void Compress() override { s_bRegistered; }

	static std::unique_ptr<ICompressionMethod> CreateMethod() { return std::make_unique<ZipCompression>(); }
	static std::string GetFactoryName() { return "ZIP"; }
	virtual std::string SAYMYNAME() {return "HELLO THERE";};

private:
	//static bool s_registered;
};

//bool ZipCompression::s_registered = CompressionMethodFactory::Register(ZipCompression::GetFactoryName(), ZipCompression::CreateMethod);


class BZCompression : public ICompressionMethod, RegisteredInFactory<BZCompression>
{
public:
//	virtual void Compress() override {s_bRegistered; }

	static std::unique_ptr<ICompressionMethod> CreateMethod() { return std::make_unique<BZCompression>(); }
	static std::string GetFactoryName() { return "BZ"; }
	virtual std::string SAYMYNAME() {return "GENERAL KENOBI";};

private:
	//static bool s_registered;
};

//bool BZCompression::s_registered = CompressionMethodFactory::Register(BZCompression::GetFactoryName(), BZCompression::CreateMethod);

int main()
{
    std::cout << "main starts...\n";
    auto pMethod = CompressionMethodFactory::Create("ZIP");
    std::cout << "created\n" << pMethod->SAYMYNAME() << std::endl;
}



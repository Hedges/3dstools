#pragma once
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "types.h"

class ByteBuffer
{
public:
	ByteBuffer() :
		m_Buffer(NULL),
		m_Size(0),
		m_ApparentSize(0)
	{

	}

	~ByteBuffer()
	{
		freeMemory();
	}

	int alloc(size_t size)
	{
		if (size > m_Size)
		{
			freeMemory();
			return allocMemory(size);
		}
		else
		{
			m_ApparentSize = size;
			clearMemory();
		}
		return 0;
	}

	int openFile(const char* path)
	{
		FILE *fp;
		size_t filesz, filepos;
		const size_t BLOCK_SIZE = 0x100000;

		if ((fp = fopen(path, "rb")) == NULL)
		{
			return 1;
		}

		fseek(fp, 0, SEEK_END);
		filesz = ftell(fp);
		rewind(fp);

		if (alloc(filesz) != 0)
		{
			fclose(fp);
			return 1;
		}

		for (filepos=0; filesz > BLOCK_SIZE; filesz -= BLOCK_SIZE, filepos += BLOCK_SIZE)
		{
			fread(data()+filepos, 1, BLOCK_SIZE, fp);
		}
		if (filesz)
		{
			fread(data() + filepos, 1, filesz, fp);
		}

		fclose(fp);

		return 0;
	}

	size_t size() const
	{
		return m_ApparentSize;
	}

	byte_t* data()
	{
		return m_Buffer;
	}

	const byte_t* dataConst() const
	{
		return m_Buffer;
	}

private:
	byte_t *m_Buffer;
	size_t m_Size;
	size_t m_ApparentSize;

	void freeMemory()
	{
		free(m_Buffer);
		m_Size = 0;
		m_ApparentSize = 0;
	}

	int allocMemory(size_t size)
	{
		m_Size = size;
		m_ApparentSize = size;
		if ((m_Buffer = (byte_t*)malloc(m_Size)) == NULL)
		{
			fprintf(stderr, "[ERROR] Cannot allocate memory!\n");
			return 1;
		}
		clearMemory();
		return 0;
	}

	void clearMemory()
	{
		memset(m_Buffer, 0, m_ApparentSize);
	}
};